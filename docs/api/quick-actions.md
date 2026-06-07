# Quick Actions API Reference

**Base URL:** `http://quick-actions:3950`

All endpoints return JSON. The `Content-Type` response header is always `application/json`. Errors include an `error` string field; orchestration failures also include `completedSteps` and `failedAt`.

**Rate limit:** 200 requests per minute per IP on `/api/` routes. Exceeded requests return `429 { "success": false, "error": "Too many requests, please slow down." }`.

---

## Service Principals

### POST /api/quick/service-principals

Create a new service principal — an application identity registered across Active Directory, Kerberos, and the OAuth provider.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `appName` | string | Yes | Application name. Used as sAMAccountName and in the Kerberos SPN (`app/{appName}@REALM`). Must be unique. |
| `description` | string | No | Human-readable description stored on the AD service account. |
| `permissions` | string[] | No | Permission keys to grant. Accepted values: `read-users`, `read-devices`, `write-policies`, `admin-access`, `api-gateway`, `audit-logs`. |
| `createdBy` | string | No | Username or ID of the actor creating this SP, recorded in audit logs. |

**Response 201** (all 5 steps succeeded):

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` |
| `clientId` | string | UUID — the application's unique OAuth client identifier |
| `clientSecret` | string | 64-character hex string. Shown once — store immediately in a secret manager. |
| `spn` | string | Kerberos Service Principal Name: `app/{appName}@REALM` |
| `serviceAccountDn` | string | Distinguished Name in AD: `CN={appName}$,CN=ServiceAccounts,DC=...` |
| `permissions` | string[] | The permissions that were successfully assigned |
| `completedSteps` | string[] | Names of all steps that completed |
| `warnings` | string[] | Non-fatal warnings (e.g., Kerberos KDC unreachable — clientId/clientSecret still usable) |

**Response 207** (partial success — some steps failed):

```json
{
  "success": false,
  "clientId": "uuid-if-created",
  "clientSecret": null,
  "completedSteps": ["createAdServiceAccount", "registerOAuthClient"],
  "failedAt": "createKerberosSpn",
  "error": "Kerberos KDC unreachable: ECONNREFUSED"
}
```

**Example:**

```bash
curl -X POST http://localhost:3950/api/quick/service-principals \
  -H "Content-Type: application/json" \
  -d '{
    "appName": "my-crm-app",
    "description": "CRM application service account",
    "permissions": ["read-users", "read-devices"]
  }'
```

```json
{
  "success": true,
  "clientId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "clientSecret": "a8f2e1b0c4d3...64chars",
  "spn": "app/my-crm-app@OPENDIRECTORY.LOCAL",
  "serviceAccountDn": "CN=my-crm-app$,CN=ServiceAccounts,DC=opendirectory,DC=local",
  "permissions": ["read-users", "read-devices"],
  "completedSteps": ["createAdServiceAccount","registerOAuthClient","createKerberosSpn","assignPermissions","storeCredentials"],
  "warnings": []
}
```

---

### GET /api/quick/service-principals

List all service principals. Retrieves from the authentication service and enriches with AD and Kerberos metadata.

**Response 200:**

```json
{
  "success": true,
  "servicePrincipals": [
    {
      "id": "uuid",
      "clientId": "uuid",
      "appName": "my-crm-app",
      "description": "CRM application service account",
      "spn": "app/my-crm-app@OPENDIRECTORY.LOCAL",
      "permissions": ["read-users"],
      "createdAt": "2026-06-07T10:00:00.000Z",
      "createdBy": "admin"
    }
  ],
  "total": 1
}
```

```bash
curl http://localhost:3950/api/quick/service-principals
```

---

### GET /api/quick/service-principals/:id

Get full details for a single service principal including AD object, Kerberos principal, and OAuth client registration status.

**Path parameter:** `id` — the `clientId` UUID returned at creation time.

**Response 200:**

```json
{
  "success": true,
  "id": "uuid",
  "clientId": "uuid",
  "appName": "my-crm-app",
  "spn": "app/my-crm-app@OPENDIRECTORY.LOCAL",
  "serviceAccountDn": "CN=my-crm-app$,CN=ServiceAccounts,...",
  "permissions": ["read-users", "read-devices"],
  "adStatus": "active",
  "kerberosStatus": "active",
  "oauthStatus": "active",
  "createdAt": "2026-06-07T10:00:00.000Z"
}
```

```bash
curl http://localhost:3950/api/quick/service-principals/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

### DELETE /api/quick/service-principals/:id

Revoke and permanently delete a service principal from all systems (AD, Kerberos, OAuth). This operation is irreversible.

**Path parameter:** `id` — the `clientId` UUID.

**Response 200:**

```json
{
  "success": true,
  "id": "uuid",
  "deletedSystems": ["active-directory", "kerberos", "oauth"],
  "completedSteps": ["revokeOAuthClient","deleteAdServiceAccount","deleteKerberosPrincipal"]
}
```

```bash
curl -X DELETE http://localhost:3950/api/quick/service-principals/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

### POST /api/quick/service-principals/:id/rotate-secret

Generate a new `clientSecret` and propagate it to all systems that store it. The old secret is immediately invalidated. The new secret is returned in the response and shown only once.

**Path parameter:** `id` — the `clientId` UUID.

**Request body:** Empty.

**Response 200:**

```json
{
  "success": true,
  "id": "uuid",
  "newClientSecret": "b9e3f2c1d4...64chars",
  "rotatedAt": "2026-06-07T12:00:00.000Z",
  "updatedSystems": ["oauth", "active-directory"]
}
```

```bash
curl -X POST http://localhost:3950/api/quick/service-principals/a1b2c3d4/rotate-secret
```

---

## Device Enrollment

### POST /api/quick/devices/enroll

Enroll a single device. Platform-specific enrollment steps are executed automatically.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `platform` | string | Yes | `macos`, `windows`, `linux`, `ios`, `android` |
| `deviceName` | string | Yes | Computer/device name (NetBIOS-compatible for Windows/Linux) |
| `serialNumber` | string | No | Hardware serial number for inventory |
| `enrollmentToken` | string | No | Pre-generated enrollment token (optional override) |
| `assignedUserId` | string | No | User UUID to assign the device to |
| `ouDn` | string | No | Target OU for AD computer account (default: `CN=Computers,...`) |

**Response 201** (or 207 on partial success):

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Overall success |
| `deviceId` | string | UUID of the created device record |
| `deviceName` | string | Resolved device name |
| `platform` | string | Confirmed platform |
| `platformConfig` | object | Platform-specific config (see below) |
| `completedSteps` | string[] | Steps completed |
| `warnings` | string[] | Non-fatal issues |

**`platformConfig` by platform:**

| Platform | Key | Description |
|---|---|---|
| `macos` | `apnsToken` | APNS device push token |
| `macos` | `mdmProfileUrl` | URL to the MDM enrollment profile |
| `macos` | `baselinePolicy` | ID of the applied macOS baseline policy |
| `windows` | `machinePassword` | Machine account password for domain join |
| `windows` | `winrmConfig` | PowerShell block to configure WinRM |
| `windows` | `gpoId` | ID of the applied Windows GPO |
| `linux` | `sssdConfig` | Content of `/etc/sssd/sssd.conf` |
| `linux` | `keytabPath` | Path to the device Kerberos keytab |
| `linux` | `hardeningPolicy` | ID of the applied hardening policy |
| `ios` | `mdmEnrollmentUrl` | MDM enrollment URL |
| `ios` | `qrCodeData` | Base64-encoded QR code PNG |
| `android` | `mdmEnrollmentUrl` | MDM enrollment URL |
| `android` | `qrCodeData` | Base64-encoded QR code PNG |

```bash
# Enroll a macOS device
curl -X POST http://localhost:3950/api/quick/devices/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "macos",
    "deviceName": "MacBook-Alice",
    "serialNumber": "C02XL0HJJGH6",
    "assignedUserId": "user-uuid",
    "ouDn": "OU=Laptops,OU=Workstations,DC=corp,DC=example,DC=com"
  }'
```

```json
{
  "success": true,
  "deviceId": "dev-uuid",
  "deviceName": "MacBook-Alice",
  "platform": "macos",
  "platformConfig": {
    "apnsToken": "abc123...",
    "mdmProfileUrl": "https://mdm.corp.example.com/enroll/dev-uuid.mobileconfig",
    "baselinePolicy": "pol-macos-baseline"
  },
  "completedSteps": ["createDeviceRecord","generateApnsToken","createMdmProfile","applyBaselinePolicy","createAdComputerAccount"],
  "warnings": []
}
```

---

### POST /api/quick/devices/bulk-enroll

Enroll multiple devices in parallel. All devices are processed concurrently; results are returned as an array.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `devices` | array | Yes | Non-empty array of device objects (same fields as single enroll) |

**Response 200:**

```json
{
  "success": true,
  "results": [
    { "deviceName": "PC001", "success": true, "deviceId": "dev-1" },
    { "deviceName": "MB002", "success": false, "error": "Duplicate serial number" }
  ],
  "enrolled": 1,
  "failed": 1,
  "total": 2
}
```

```bash
curl -X POST http://localhost:3950/api/quick/devices/bulk-enroll \
  -H "Content-Type: application/json" \
  -d '{
    "devices": [
      {"platform":"windows","deviceName":"PC001","serialNumber":"SN001"},
      {"platform":"macos","deviceName":"MB002","serialNumber":"SN002"}
    ]
  }'
```

---

### GET /api/quick/devices/:id/enrollment-status

Get the current enrollment state of a device, checking both MDM and AD enrollment.

**Response 200:**

```json
{
  "success": true,
  "deviceId": "dev-uuid",
  "mdmEnrolled": true,
  "adJoined": true,
  "complianceStatus": "compliant",
  "lastSeen": "2026-06-07T11:45:00.000Z",
  "platform": "macos",
  "assignedUser": "user-uuid"
}
```

---

### POST /api/quick/devices/:id/unenroll

Unenroll a device from MDM and optionally perform a remote wipe.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `wipe` | boolean | No | If `true`, trigger a remote factory reset before unenrolling. Default: `false`. |

**Response 200:**

```json
{
  "success": true,
  "deviceId": "dev-uuid",
  "wiped": false,
  "completedSteps": ["revokeMdmProfile","removeAdComputerAccount","releaseDeviceRecord"]
}
```

---

## User Lifecycle

### POST /api/quick/users/onboard

Onboard a new employee across all systems in a 7-step workflow.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `firstName` | string | Yes | First name |
| `lastName` | string | Yes | Last name |
| `email` | string | Yes | Corporate email address |
| `department` | string | No | Department name (used for OU placement and group membership) |
| `jobTitle` | string | No | Job title stored in the directory |
| `role` | string | No | Initial role assignment. Default: `user` |
| `manager` | string | No | Manager's user ID — sets the `manager` attribute in AD |
| `assignDeviceId` | string | No | Pre-existing device UUID to assign to this user |

**Orchestration steps:**
1. `createDirectoryUser` — AD/LDAP object in the department OU
2. `createAuthAccount` — Auth account with auto-generated temporary password
3. `createKerberosPrincipal` — KDC principal synced from auth registration
4. `assignRole` — PIM/RBAC role assignment in conditional-access
5. `addToGroup` — Add to department security group
6. `sendWelcomeEmail` — Notification with temporary password and login instructions
7. `assignDevice` — Only if `assignDeviceId` supplied

**Response 201** (or 207 partial):

```json
{
  "success": true,
  "userId": "user-uuid",
  "username": "alice.smith",
  "temporaryPassword": "Temp1234!",
  "directoryDn": "CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com",
  "completedSteps": ["createDirectoryUser","createAuthAccount","createKerberosPrincipal","assignRole","addToGroup","sendWelcomeEmail"],
  "warnings": []
}
```

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

---

### POST /api/quick/users/:id/offboard

Offboard a departing employee across all systems in 6 steps.

**Path parameter:** `id` — user UUID.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `revokeDevices` | boolean | No | Wipe and unenroll all assigned devices. Default: `false`. |
| `transferFilesTo` | string | No | User ID to transfer file/resource ownership to. |
| `disableAccount` | boolean | No | If `true`, disable rather than delete. Default: `true`. |

**Offboarding steps:**
1. `disableAuthAccount` — Disable (or delete) auth account, revoke all tokens
2. `revokeSessions` — Terminate all active sessions
3. `revokePimElevations` — End any active PIM role elevations
4. `revokeDevices` — Wipe/unenroll assigned devices (if requested)
5. `removeGroupMemberships` — Remove from all security groups
6. `disableKerberosPrincipal` — Lock the Kerberos principal

**Response 200:**

```json
{
  "success": true,
  "userId": "user-uuid",
  "completedSteps": ["disableAuthAccount","revokeSessions","revokePimElevations","removeGroupMemberships","disableKerberosPrincipal"],
  "devicesRevoked": 0
}
```

```bash
curl -X POST "http://localhost:3950/api/quick/users/user-uuid/offboard" \
  -H "Content-Type: application/json" \
  -d '{"revokeDevices": true, "disableAccount": true}'
```

---

## Policy Deployment

### POST /api/quick/policies/deploy

Deploy a policy to a target. The service fetches the policy, compiles it for the target platform, and creates the assignment and link in the policy-service.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `policyId` | string | Yes | Policy ID to deploy |
| `targetType` | string | Yes | `user`, `group`, `ou`, `device`, `all` |
| `targetId` | string | No | Target UUID. Required unless `targetType` is `all`. |
| `enforced` | boolean | No | Enforce the policy (blocks inheritance). Default: `false`. |
| `dryRun` | boolean | No | If `true`, validate and return what would be applied without making changes. Default: `false`. |

**Response 200** (or 207):

```json
{
  "success": true,
  "deploymentId": "deploy-uuid",
  "policyId": "pol-uuid",
  "targetType": "ou",
  "targetId": "ou-uuid",
  "enforced": false,
  "dryRun": false,
  "affectedObjects": 42,
  "completedSteps": ["fetchPolicy","compileForPlatform","createAssignment","createLink","notifyDevices"]
}
```

```bash
curl -X POST http://localhost:3950/api/quick/policies/deploy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policyId": "pol-uuid",
    "targetType": "ou",
    "targetId": "ou-uuid",
    "enforced": true
  }'
```

---

### GET /api/quick/policies/deployments/:id

Get the status and details of a policy deployment.

**Response 200:**

```json
{
  "success": true,
  "deploymentId": "deploy-uuid",
  "policyId": "pol-uuid",
  "status": "applied",
  "targetType": "ou",
  "targetId": "ou-uuid",
  "enforced": false,
  "deployedAt": "2026-06-07T11:00:00.000Z",
  "affectedObjects": 42,
  "complianceRate": 0.95
}
```

Returns `404` if the deployment ID is not found.

---

### POST /api/quick/policies/deployments/:id/rollback

Roll back a deployment by removing all links and assignments created during the deployment.

**Response 200:**

```json
{
  "success": true,
  "deploymentId": "deploy-uuid",
  "rolledBackAt": "2026-06-07T12:00:00.000Z",
  "removedLinks": 1,
  "removedAssignments": 42
}
```

---

## Compliance & Status

### GET /api/quick/compliance/snapshot

Aggregate compliance overview across all active policies and managed devices.

**Response 200:**

```json
{
  "success": true,
  "totalDevices": 145,
  "compliantDevices": 138,
  "nonCompliantDevices": 7,
  "complianceRate": 0.952,
  "topViolations": [
    {
      "policyId": "pol-uuid",
      "policyName": "BitLocker Enforcement",
      "violatingDevices": 4,
      "severity": "high"
    },
    {
      "policyId": "pol-uuid-2",
      "policyName": "OS Patch Level",
      "violatingDevices": 3,
      "severity": "medium"
    }
  ],
  "byPlatform": {
    "windows": { "total": 80, "compliant": 76 },
    "macos": { "total": 45, "compliant": 44 },
    "linux": { "total": 20, "compliant": 18 }
  },
  "snapshotAt": "2026-06-07T12:00:00.000Z"
}
```

```bash
curl http://localhost:3950/api/quick/compliance/snapshot \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /api/quick/status

Ping all registered downstream services and return a unified health report.

**Response 200:**

```json
{
  "services": {
    "authentication-service": { "healthy": true, "latencyMs": 12 },
    "enterprise-directory": { "healthy": true, "latencyMs": 8 },
    "device-service": { "healthy": true, "latencyMs": 15 },
    "policy-service": { "healthy": true, "latencyMs": 6 },
    "kerberos-kdc": { "healthy": false, "error": "ECONNREFUSED" },
    "samba-ad-dc": { "healthy": true, "latencyMs": 22 }
  },
  "overall": "degraded",
  "checkedAt": "2026-06-07T12:00:00.000Z"
}
```

`overall`: `"healthy"` (all services up), `"degraded"` (some down), `"unhealthy"` (all down).

```bash
curl http://localhost:3950/api/quick/status
```

---

### GET /health

Service health. Does not check downstream services.

**Response 200:**

```json
{
  "status": "healthy",
  "service": "quick-actions",
  "timestamp": "2026-06-07T12:00:00.000Z",
  "uptime": 7200.3
}
```

---

## Error Reference

| HTTP Status | Meaning |
|---|---|
| `201` | All orchestration steps succeeded |
| `207` | Partial success — check `completedSteps` and `failedAt` |
| `400` | Bad request — missing or invalid required fields |
| `404` | Resource not found (deployment ID, service principal ID, etc.) |
| `429` | Rate limit exceeded |
| `500` | Unhandled internal error |

All error responses include `{ "success": false, "error": "message" }`. Orchestration failures additionally include `completedSteps` (array) and `failedAt` (string) fields.
