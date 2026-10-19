# Device Service API Reference

**Base URL:** `http://device-service:3003`

**Authentication:** `Authorization: Bearer <token>` required on all `/api/` routes except enrollment initiation. Device agents may also authenticate via `X-Device-ID` header for WebSocket connections.

**Rate limits:** Dynamic per device type — admin: 10,000 req/15min; server: 5,000; workstation: 1,000; default: 500. Limits are skipped in development.

---

## Device CRUD

### GET /api/devices

List managed devices with optional filtering and pagination.

**Query parameters:**

| Parameter | Description |
|---|---|
| `platform` | Filter by platform: `macos`, `windows`, `linux`, `ios`, `android` |
| `status` | Filter by status: `active`, `inactive`, `enrolled`, `pending` |
| `assignedUser` | Filter by assigned user ID |
| `search` | Text search across device name and serial number |
| `page` | Page number (default: 1) |
| `limit` | Results per page (default: 50, max: 200) |

**Response 200:**

```json
{
  "devices": [
    {
      "id": "dev-uuid",
      "deviceName": "MacBook-Alice",
      "platform": "macos",
      "serialNumber": "C02XL0HJJGH6",
      "status": "active",
      "assignedUser": "user-uuid",
      "enrolledAt": "2026-06-01T09:00:00.000Z",
      "lastSeen": "2026-06-07T11:45:00.000Z",
      "complianceStatus": "compliant"
    }
  ],
  "total": 145,
  "page": 1,
  "limit": 50
}
```

```bash
curl "http://localhost:3003/api/devices?platform=macos&page=1" \
  -H "Authorization: Bearer $TOKEN"
```

---

### POST /api/devices

Register a new device record without going through the full enrollment workflow.

**Request body:**

```json
{
  "deviceName": "MacBook-Bob",
  "platform": "macos",
  "serialNumber": "C02XXXXJGH6",
  "assignedUser": "user-uuid",
  "manufacturer": "Apple",
  "model": "MacBook Pro 14",
  "osVersion": "15.2"
}
```

**Response 201:** Device record with generated UUID.

---

### GET /api/devices/:deviceId

Get full device details including compliance status, certificates, and assigned policies.

```bash
curl http://localhost:3003/api/devices/dev-uuid \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "id": "dev-uuid",
  "deviceName": "MacBook-Alice",
  "platform": "macos",
  "serialNumber": "C02XL0HJJGH6",
  "manufacturer": "Apple",
  "model": "MacBook Pro 14-inch",
  "osVersion": "15.2",
  "status": "active",
  "enrolledAt": "2026-06-01T09:00:00.000Z",
  "lastSeen": "2026-06-07T11:45:00.000Z",
  "assignedUser": "user-uuid",
  "complianceStatus": "compliant",
  "policies": ["pol-uuid-1", "pol-uuid-2"],
  "certificates": [],
  "location": null
}
```

---

### PUT /api/devices/:deviceId

Update device metadata.

```bash
curl -X PUT http://localhost:3003/api/devices/dev-uuid \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"osVersion": "15.3", "notes": "Updated OS"}'
```

---

### DELETE /api/devices/:deviceId

Remove a device from management. Does not perform remote wipe.

---

### POST /api/devices/:deviceId/lock

Send a lock command to the device via the WebSocket agent channel.

```bash
curl -X POST http://localhost:3003/api/devices/dev-uuid/lock \
  -H "Authorization: Bearer $TOKEN"
```

---

### POST /api/devices/:deviceId/wipe

Initiate a remote factory reset. **Irreversible.**

```bash
curl -X POST http://localhost:3003/api/devices/dev-uuid/wipe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Device lost — confirmed by security team"}'
```

---

## Enrollment

### POST /api/enrollment/initiate

Start a new device enrollment workflow. Returns an `enrollmentId` and enrollment token that the device agent uses to complete enrollment.

**Request body:**

```json
{
  "platform": "macos",
  "deviceName": "MacBook-Carol",
  "serialNumber": "C02NEWSERIAL",
  "requestedBy": "user-uuid"
}
```

**Response 200:**

```json
{
  "enrollmentId": "enroll-uuid",
  "enrollmentToken": "eyJhbGciOiJIUzI1...",
  "expiresAt": "2026-06-07T14:00:00.000Z",
  "instructions": {
    "macos": "Install the MDM profile from https://mdm.example.com/enroll/enroll-uuid"
  }
}
```

---

### POST /api/enrollment/complete

Complete enrollment. Called by the device agent after the user installs the MDM profile or domain-join script.

**Request body:**

```json
{
  "enrollmentId": "enroll-uuid",
  "enrollmentToken": "eyJhbGciOiJIUzI1...",
  "deviceFingerprint": "sha256:abc123",
  "agentVersion": "1.5.2"
}
```

**Response 200:**

```json
{
  "success": true,
  "deviceId": "dev-uuid",
  "enrolled": true,
  "policies": ["pol-uuid-baseline"]
}
```

---

### GET /api/enrollment/:enrollmentId/status

Check the status of a pending enrollment.

```bash
curl http://localhost:3003/api/enrollment/enroll-uuid/status \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "enrollmentId": "enroll-uuid",
  "status": "pending_approval",
  "deviceName": "MacBook-Carol",
  "platform": "macos",
  "requestedAt": "2026-06-07T12:00:00.000Z",
  "expiresAt": "2026-06-07T14:00:00.000Z"
}
```

Status values: `pending`, `pending_approval`, `approved`, `rejected`, `completed`, `expired`.

---

### POST /api/enrollment/:enrollmentId/approve

Admin approval for enrollment requests that require manual review.

```bash
curl -X POST http://localhost:3003/api/enrollment/enroll-uuid/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approvedBy": "admin-uuid", "notes": "Approved for new hire"}'
```

---

## Compliance

### GET /api/compliance/scan/:deviceId

Trigger a compliance scan for a specific device. Checks all active policies against the device's current state.

```bash
curl http://localhost:3003/api/compliance/scan/dev-uuid \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "deviceId": "dev-uuid",
  "scannedAt": "2026-06-07T12:00:00.000Z",
  "overallStatus": "non_compliant",
  "violations": [
    {
      "violationId": "viol-uuid",
      "policyId": "pol-uuid",
      "policyName": "BitLocker Enforcement",
      "rule": "disk_encryption_required",
      "severity": "high",
      "remediationAvailable": true
    }
  ],
  "passedChecks": 14,
  "failedChecks": 1
}
```

---

### GET /api/compliance/violations

List all open compliance violations across all devices.

**Query parameters:** `?deviceId=`, `?policyId=`, `?severity=high|medium|low`, `?page=`, `?limit=`

**Response 200:**

```json
{
  "violations": [
    {
      "violationId": "viol-uuid",
      "deviceId": "dev-uuid",
      "deviceName": "MacBook-Alice",
      "policyId": "pol-uuid",
      "policyName": "BitLocker Enforcement",
      "severity": "high",
      "detectedAt": "2026-06-07T10:00:00.000Z",
      "remediationAvailable": true
    }
  ],
  "total": 7
}
```

---

### POST /api/compliance/remediate/:violationId

Trigger automated remediation for a specific violation.

```bash
curl -X POST http://localhost:3003/api/compliance/remediate/viol-uuid \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "violationId": "viol-uuid",
  "remediationTriggered": true,
  "actionId": "action-uuid",
  "estimatedDuration": 60
}
```

---

## Remote Actions

### POST /api/remote/execute

Execute a remote action on a managed device via the WebSocket agent channel.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `deviceId` | string | Yes | Target device UUID |
| `action` | string | Yes | Action name (see below) |
| `parameters` | object | No | Action-specific parameters |
| `requestedBy` | string | No | Actor ID for audit logging |

**Supported actions:** `lock`, `unlock`, `restart`, `shutdown`, `run-script`, `install-package`, `uninstall-package`, `update-inventory`, `collect-logs`, `rotate-password`

```bash
curl -X POST http://localhost:3003/api/remote/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "dev-uuid",
    "action": "run-script",
    "parameters": {
      "script": "#!/bin/bash\necho 'compliance check' > /tmp/check.log",
      "timeout": 30
    }
  }'
```

**Response 200:**

```json
{
  "actionId": "action-uuid",
  "deviceId": "dev-uuid",
  "action": "run-script",
  "status": "queued",
  "queuedAt": "2026-06-07T12:00:00.000Z"
}
```

If the device agent is connected via WebSocket, the action is delivered immediately and `status` is `delivered`. Otherwise, it is queued until the agent reconnects.

---

### GET /api/remote/actions/:actionId/status

Poll for remote action completion.

**Response 200:**

```json
{
  "actionId": "action-uuid",
  "deviceId": "dev-uuid",
  "action": "run-script",
  "status": "completed",
  "result": {
    "exitCode": 0,
    "stdout": "",
    "stderr": ""
  },
  "completedAt": "2026-06-07T12:00:05.000Z"
}
```

Status values: `queued`, `delivered`, `executing`, `completed`, `failed`, `timed_out`.

---

### POST /api/remote/bulk-action

Execute the same action on multiple devices in parallel.

**Request body:**

```json
{
  "deviceIds": ["dev-uuid-1", "dev-uuid-2", "dev-uuid-3"],
  "action": "lock",
  "parameters": {}
}
```

**Response 200:**

```json
{
  "bulkActionId": "bulk-uuid",
  "total": 3,
  "queued": 3,
  "actionIds": {
    "dev-uuid-1": "action-uuid-1",
    "dev-uuid-2": "action-uuid-2",
    "dev-uuid-3": "action-uuid-3"
  }
}
```

---

## Analytics

### GET /api/analytics/dashboard

Overall device analytics dashboard.

```bash
curl http://localhost:3003/api/analytics/dashboard \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "totalDevices": 145,
  "activeDevices": 138,
  "enrolledThisWeek": 12,
  "complianceRate": 0.952,
  "byPlatform": {
    "macos": 45, "windows": 80, "linux": 20
  },
  "topIssues": ["outdated-os", "missing-encryption", "no-agent"],
  "generatedAt": "2026-06-07T12:00:00.000Z"
}
```

---

### GET /api/analytics/threats

Active threat detections from the analytics bridge.

**Query parameters:** `?severity=critical|high|medium|low`, `?limit=50`

**Response 200:**

```json
{
  "success": true,
  "data": [
    {
      "threatId": "threat-uuid",
      "deviceId": "dev-uuid",
      "type": "malware",
      "severity": "high",
      "detectedAt": "2026-06-07T11:00:00.000Z",
      "description": "Suspicious process detected"
    }
  ],
  "total": 2
}
```

---

### GET /api/analytics/anomalies

Behavioral anomaly detections.

**Query parameters:** `?deviceId=`, `?limit=50`

---

### GET /api/analytics/predictions

ML-based predictions for device failures or compliance drift.

**Query parameters:** `?type=failure|compliance|security`, `?deviceId=`

---

## Health Check

### GET /health

Returns detailed service health including database, cache, event bus, and live metrics.

```bash
curl http://localhost:3003/health
```

**Response 200:**

```json
{
  "status": "healthy",
  "service": "device-management-service",
  "version": "1.0.0",
  "uptime": 86400,
  "timestamp": "2026-06-07T12:00:00.000Z",
  "checks": {
    "database": { "status": "healthy" },
    "cache": { "status": "healthy" },
    "eventBus": { "status": "healthy" }
  },
  "metrics": {
    "activeDevices": 138,
    "pendingEnrollments": 3,
    "complianceViolations": 7,
    "wsConnections": 98
  }
}
```

Returns `503` if any check reports unhealthy.
