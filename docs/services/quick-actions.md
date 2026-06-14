# quick-actions

**Port:** 3950  
**Database:** None (orchestrator only)  
**Language:** Node.js 18+

## Overview

The quick-actions service is the high-level orchestration layer for OpenDirectory's most common day-two operations. Each endpoint coordinates a multi-step workflow across several downstream services (authentication-service, enterprise-directory, kerberos-kdc, samba-ad-dc, device-service, policy-service) and returns a unified result with per-step status. If a step fails, the result uses HTTP 207 (Multi-Status) so callers can identify exactly which step failed and which completed successfully.

The service uses a simple rate limiter (200 req/min per IP), compression, and structured request logging. It does not maintain its own database; all state lives in the downstream services.

**Base URL:** `http://quick-actions:3950`

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3950` | HTTP listen port |
| `AUTH_SERVICE_URL` | `http://authentication-service` | Authentication service |
| `DIRECTORY_URL` | `http://enterprise-directory` | Enterprise directory |
| `DEVICE_SERVICE_URL` | `http://device-service` | Device management service |
| `KERBEROS_KDC_URL` | `http://kerberos-kdc` | Kerberos KDC |
| `SAMBA_AD_DC_URL` | `http://samba-ad-dc` | Samba AD DC |
| `POLICY_SERVICE_URL` | `http://policy-service` | Policy service |

## API Endpoints

### Service Principals

| Method | Path | Description |
|---|---|---|
| POST | `/api/quick/service-principals` | Create service principal across all systems |
| GET | `/api/quick/service-principals` | List all service principals |
| GET | `/api/quick/service-principals/:id` | Get service principal details |
| DELETE | `/api/quick/service-principals/:id` | Revoke and delete service principal |
| POST | `/api/quick/service-principals/:id/rotate-secret` | Rotate client secret |

### Device Enrollment

| Method | Path | Description |
|---|---|---|
| POST | `/api/quick/devices/enroll` | Enroll a single device |
| POST | `/api/quick/devices/bulk-enroll` | Enroll multiple devices in parallel |
| GET | `/api/quick/devices/:id/enrollment-status` | Get device enrollment status |
| POST | `/api/quick/devices/:id/unenroll` | Unenroll device (optionally wipe) |

### User Lifecycle

| Method | Path | Description |
|---|---|---|
| POST | `/api/quick/users/onboard` | Onboard new employee (7-step workflow) |
| POST | `/api/quick/users/:id/offboard` | Offboard departing employee (6-step workflow) |

### Policy Deployment

| Method | Path | Description |
|---|---|---|
| POST | `/api/quick/policies/deploy` | Deploy policy to a target |
| GET | `/api/quick/policies/deployments/:id` | Get deployment status |
| POST | `/api/quick/policies/deployments/:id/rollback` | Roll back a deployment |

### Compliance & Status

| Method | Path | Description |
|---|---|---|
| GET | `/api/quick/compliance/snapshot` | Get compliance overview across all policies |
| GET | `/api/quick/status` | Health of all downstream services |
| GET | `/health` | quick-actions own health check |

---

## Endpoint Reference

### POST /api/quick/service-principals

Create a new service principal — an application identity — across Active Directory, Kerberos, OAuth, and the authentication service in a single call.

**Orchestration steps:**
1. Create AD service account in `CN=ServiceAccounts` container
2. Register OAuth client in authentication service
3. Create Kerberos service principal (`app/{appName}@REALM`)
4. Assign requested permissions
5. Return credentials

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `appName` | string | Yes | Application name (used as sAMAccountName) |
| `description` | string | No | Human-readable description |
| `permissions` | string[] | No | Permission keys (see below) |
| `createdBy` | string | No | Actor creating this SP |

**Permission keys:** `read-users`, `read-devices`, `write-policies`, `admin-access`, `api-gateway`, `audit-logs`

**Response 201 (all steps succeeded) or 207 (partial success):**

| Field | Description |
|---|---|
| `clientId` | UUID — application's unique identifier |
| `clientSecret` | 64-char hex secret — shown once, store securely |
| `spn` | Kerberos SPN (`app/{appName}@REALM`) |
| `serviceAccountDn` | AD DN of the service account |
| `permissions` | Assigned permissions |
| `completedSteps` | Array of step names that succeeded |
| `warnings` | Non-fatal issues (e.g., Kerberos unreachable) |

```bash
curl -X POST http://localhost:3950/api/quick/service-principals \
  -H "Content-Type: application/json" \
  -d '{
    "appName": "my-crm-app",
    "description": "CRM application service account",
    "permissions": ["read-users", "read-devices"]
  }'
```

**Error response (207):**
```json
{
  "success": false,
  "error": "Failed at step: createKerberosSpn",
  "completedSteps": ["createAdServiceAccount", "registerOAuthClient"],
  "failedAt": "createKerberosSpn"
}
```

### GET /api/quick/service-principals

List all service principals from the authentication service.

```bash
curl http://localhost:3950/api/quick/service-principals \
  -H "Authorization: Bearer $TOKEN"
```

### GET /api/quick/service-principals/:id

Get full details for a service principal, including AD object, Kerberos SPN, and OAuth client registration.

### DELETE /api/quick/service-principals/:id

Revoke and remove the service principal from all systems (AD, Kerberos, OAuth). Non-reversible.

### POST /api/quick/service-principals/:id/rotate-secret

Generate a new 64-char hex `clientSecret` and update it in the authentication service. Returns the new secret (shown once).

---

### POST /api/quick/devices/enroll

Enroll a device. Platform detection selects the appropriate enrollment steps automatically.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `platform` | string | Yes | `macos`, `windows`, `linux`, `ios`, `android` |
| `deviceName` | string | Yes | Computer or device name |
| `serialNumber` | string | No | Hardware serial number |
| `enrollmentToken` | string | No | Pre-generated enrollment token |
| `assignedUserId` | string | No | User to assign device to |
| `ouDn` | string | No | Target OU (default: `CN=Computers,...`) |

**Platform-specific steps:**

| Platform | Steps |
|---|---|
| `macos` | Create device record, generate APNS token, create MDM profile, apply baseline policy, join AD (if Samba available) |
| `windows` | Create device record, generate machine password, configure WinRM, apply GPO, join AD |
| `linux` | Create device record, generate sssd.conf, export Kerberos keytab, apply hardening policy |
| `ios` | Create device record, generate MDM enrollment URL, generate QR code |
| `android` | Create device record, generate MDM enrollment URL, generate QR code |

**Response `platformConfig` fields by platform:**

| Platform | Field | Description |
|---|---|---|
| macos | `apnsToken` | APNS push token for MDM commands |
| macos | `mdmProfileUrl` | URL to install the MDM profile |
| macos | `baselinePolicy` | Applied baseline policy ID |
| windows | `machinePassword` | AD machine account password |
| windows | `winrmConfig` | WinRM configuration script |
| windows | `gpoId` | Applied GPO ID |
| linux | `sssdConfig` | sssd.conf content |
| linux | `keytabPath` | Kerberos keytab file path |
| linux | `hardeningPolicy` | Applied hardening policy ID |
| ios | `mdmEnrollmentUrl` | MDM enrollment URL |
| ios | `qrCodeData` | Base64 QR code image |
| android | `mdmEnrollmentUrl` | MDM enrollment URL |
| android | `qrCodeData` | Base64 QR code image |

```bash
curl -X POST http://localhost:3950/api/quick/devices/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "macos",
    "deviceName": "MacBook-Alice",
    "serialNumber": "C02XL0HJJGH6",
    "assignedUserId": "user-uuid"
  }'
```

### POST /api/quick/devices/bulk-enroll

Enroll multiple devices in parallel. Supply an array of device objects with the same fields as the single enroll endpoint.

```json
{
  "devices": [
    { "platform": "windows", "deviceName": "PC001", "serialNumber": "SN001" },
    { "platform": "macos", "deviceName": "MB002", "serialNumber": "SN002" }
  ]
}
```

Returns an array of per-device results with the same schema as the single enroll response.

### GET /api/quick/devices/:id/enrollment-status

Returns the current MDM and AD enrollment status for a device. Queries the device-service and samba-ad-dc in parallel.

### POST /api/quick/devices/:id/unenroll

Unenroll and optionally wipe the device.

```json
{ "wipe": false }
```

---

### POST /api/quick/users/onboard

Create a complete employee identity in one call. The 7-step workflow creates the directory user, auth account, assigns a role, adds to the default group, sends a welcome email, optionally assigns a device, and publishes an `identity.user.created` event.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `firstName` | string | Yes | First name |
| `lastName` | string | Yes | Last name |
| `email` | string | Yes | Corporate email |
| `department` | string | No | Department name |
| `jobTitle` | string | No | Job title |
| `role` | string | No | Initial role (default: `user`) |
| `manager` | string | No | Manager's user ID |
| `assignDeviceId` | string | No | Pre-existing device to assign |

**Orchestration steps:**
1. Create directory object in enterprise-directory
2. Create auth account in authentication-service (generates temporary password)
3. Create Kerberos principal
4. Assign role in conditional-access/PIM
5. Add to department group in enterprise-directory
6. Send welcome email via notification-service
7. Assign device (if `assignDeviceId` provided)

```bash
curl -X POST http://localhost:3950/api/quick/users/onboard \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Alice",
    "lastName": "Smith",
    "email": "alice.smith@corp.example.com",
    "department": "Engineering",
    "jobTitle": "Software Engineer",
    "role": "developer"
  }'
```

**Response 201:**
```json
{
  "success": true,
  "userId": "user-uuid",
  "username": "alice.smith",
  "temporaryPassword": "Temp1234!",
  "directoryDn": "CN=Alice Smith,OU=Engineering,...",
  "completedSteps": ["createDirectoryUser","createAuthAccount","createKerberosPrincipal","assignRole","addToGroup","sendWelcomeEmail"]
}
```

### POST /api/quick/users/:id/offboard

Offboard a departing employee in 6 steps.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `revokeDevices` | boolean | No | Wipe and unenroll assigned devices |
| `transferFilesTo` | string | No | User ID to transfer file ownership to |
| `disableAccount` | boolean | No | Disable rather than delete (default: true) |

**Offboarding steps:**
1. Disable auth account (or delete if `disableAccount: false`)
2. Revoke all active sessions
3. Revoke PIM elevations
4. Disable/unenroll assigned devices
5. Remove group memberships
6. Disable Kerberos principal

---

### POST /api/quick/policies/deploy

Deploy a policy to a target. Handles lookup, compilation, and assignment in a single call.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `policyId` | string | Yes | Policy ID to deploy |
| `targetType` | string | Yes | `user`, `group`, `ou`, `device`, `all` |
| `targetId` | string | No | Target ID (required unless `targetType=all`) |
| `enforced` | boolean | No | Enforce (block inheritance) |
| `dryRun` | boolean | No | Preview without applying |

```bash
curl -X POST http://localhost:3950/api/quick/policies/deploy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policyId": "pol-uuid",
    "targetType": "ou",
    "targetId": "ou-uuid",
    "enforced": true,
    "dryRun": false
  }'
```

### GET /api/quick/policies/deployments/:id

Get the status of a policy deployment including per-target application results.

### POST /api/quick/policies/deployments/:id/rollback

Roll back a policy deployment. Removes the policy link from all targets it was deployed to.

### GET /api/quick/compliance/snapshot

Returns a quick compliance overview aggregated from the policy-service and device-service.

```json
{
  "totalDevices": 145,
  "compliantDevices": 138,
  "nonCompliantDevices": 7,
  "complianceRate": 0.952,
  "topViolations": [
    { "policyId": "pol-uuid", "policyName": "BitLocker", "violatingDevices": 4 }
  ],
  "snapshotAt": "2026-06-07T12:00:00.000Z"
}
```

### GET /api/quick/status

Ping all downstream services and return a unified health report.

```json
{
  "services": {
    "authentication-service": { "healthy": true, "latencyMs": 12 },
    "enterprise-directory": { "healthy": true, "latencyMs": 8 },
    "kerberos-kdc": { "healthy": false, "error": "ECONNREFUSED" }
  },
  "overall": "degraded",
  "checkedAt": "2026-06-07T12:00:00.000Z"
}
```

`overall` values: `healthy` (all up), `degraded` (some down), `unhealthy` (all down).

### GET /health

```json
{
  "status": "healthy",
  "service": "quick-actions",
  "timestamp": "2026-06-07T12:00:00.000Z",
  "uptime": 3600.5
}
```

## Error Handling

All orchestration endpoints use HTTP 201 for complete success and 207 for partial success (some steps completed, some failed). Full failure returns 400 or 500 as appropriate.

Error response schema:
```json
{
  "success": false,
  "error": "Descriptive error message",
  "completedSteps": ["step1", "step2"],
  "failedAt": "step3"
}
```

Rate limit responses (429):
```json
{ "success": false, "error": "Too many requests, please slow down." }
```
