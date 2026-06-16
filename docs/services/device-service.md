# device-service

**Port:** 3003  
**Database:** PostgreSQL (devices), Redis (cache)  
**Language:** Node.js 18+

## Overview

The device management service is the MDM backbone of OpenDirectory. It manages the full lifecycle of Windows, macOS, Linux, iOS, and Android devices: registration, enrollment approval workflows, policy assignment, continuous compliance scanning, and remote action execution. Devices connect over a WebSocket channel at `ws://device-service:3003/ws/devices` for real-time bidirectional command delivery. The service integrates with an AI analytics bridge for threat detection, anomaly scoring, and predictive failure analysis.

Compliance scan results and remote action outcomes are published to the event bus, enabling the policy-service and conditional-access service to react in real time. Bulk import, backup/DR orchestration, and update management are supported through proxy routes to companion services.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3003` | HTTP listen port |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_NAME` | `devices` | PostgreSQL database name |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | — | PostgreSQL password |
| `REDIS_HOST` | `redis` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `RABBITMQ_URL` | `amqp://rabbitmq:5672` | RabbitMQ (device command queue) |
| `EVENT_BUS_URL` | — | gRPC event bus endpoint |
| `BACKUP_SERVICE_URL` | `http://backup-service` | Backup service base URL |
| `UPDATE_SERVICE_URL` | `http://update-management` | Update management base URL |
| `NETWORK_PROFILE_URL` | `http://certificate-network` | Network profile service URL |
| `LICENSE_SERVICE_URL` | `http://license-management` | License management URL |

## API Endpoints

### Device CRUD

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/devices` | List devices (supports filtering, pagination) | Yes |
| POST | `/api/devices` | Register a new device | Yes |
| GET | `/api/devices/:deviceId` | Get device details | Yes |
| PUT | `/api/devices/:deviceId` | Update device attributes | Yes |
| DELETE | `/api/devices/:deviceId` | Remove device | Yes |
| POST | `/api/devices/:deviceId/lock` | Send lock command | Yes |
| POST | `/api/devices/:deviceId/unlock` | Send unlock command | Yes |
| POST | `/api/devices/:deviceId/wipe` | Initiate remote wipe | Yes |
| GET | `/api/devices/:deviceId/stammdaten` | Get device master data | Yes |
| PUT | `/api/devices/:deviceId/stammdaten` | Update device master data | Yes |
| POST | `/api/devices/:deviceId/photo` | Upload device photo | Yes |
| GET | `/api/devices/:deviceId/photo` | Get device photo | Yes |

### Enrollment

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/enrollment/initiate` | Start enrollment workflow | No |
| POST | `/api/enrollment/complete` | Complete enrollment with token | No |
| POST | `/api/enrollment/verify` | Verify enrollment token | No |
| GET | `/api/enrollment/:enrollmentId/status` | Get enrollment status | Yes |
| POST | `/api/enrollment/:enrollmentId/approve` | Admin approve enrollment | Admin |
| POST | `/api/enrollment/:enrollmentId/reject` | Admin reject enrollment | Admin |

### Policy (device-local)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies` | List device policies | Yes |
| POST | `/api/policies` | Create device policy | Yes |
| GET | `/api/policies/:policyId` | Get policy | Yes |
| PUT | `/api/policies/:policyId` | Update policy | Yes |
| DELETE | `/api/policies/:policyId` | Delete policy | Yes |
| POST | `/api/policies/:policyId/assign` | Assign policy to device(s) | Yes |
| POST | `/api/policies/:policyId/deploy` | Deploy policy immediately | Yes |

### Compliance

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/compliance/scan/:deviceId` | Trigger compliance scan | Yes |
| GET | `/api/compliance/violations` | List all open violations | Yes |
| POST | `/api/compliance/remediate/:violationId` | Trigger automated remediation | Yes |
| GET | `/api/compliance/reports` | List compliance reports | Yes |

### Remote Actions

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/remote/execute` | Execute a remote action on a device | Yes |
| GET | `/api/remote/actions/:actionId/status` | Get action execution status | Yes |
| POST | `/api/remote/bulk-action` | Execute action on multiple devices | Yes |

### Analytics

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/analytics/dashboard` | Overall device analytics dashboard | Yes |
| GET | `/api/analytics/device-trends` | Device count and platform trends | Yes |
| GET | `/api/analytics/compliance-metrics` | Aggregate compliance metrics | Yes |
| GET | `/api/analytics/security-insights` | Security posture insights | Yes |
| GET | `/api/analytics/threats` | Active threat detections (supports `?severity=high&limit=20`) | Yes |
| GET | `/api/analytics/anomalies` | Behavioral anomalies (supports `?deviceId=...`) | Yes |
| GET | `/api/analytics/predictions` | Predictive failure/risk predictions | Yes |
| GET | `/api/analytics/recommendations` | Remediation recommendations | Yes |

### Certificates

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/certificates` | List device certificates | Yes |
| POST | `/api/certificates/issue` | Issue certificate for device | Yes |
| POST | `/api/certificates/:certId/renew` | Renew expiring certificate | Yes |
| POST | `/api/certificates/:certId/revoke` | Revoke certificate | Yes |

### Geofencing

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/geofencing/zones` | List geofencing zones | Yes |
| POST | `/api/geofencing/zones` | Create geofencing zone | Yes |
| PUT | `/api/geofencing/zones/:zoneId` | Update zone | Yes |
| DELETE | `/api/geofencing/zones/:zoneId` | Delete zone | Yes |

### Bulk Operations

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/bulk/import-devices` | Bulk import devices from CSV/JSON | Yes |
| POST | `/api/bulk/update-policies` | Bulk policy update | Yes |
| POST | `/api/bulk/compliance-scan` | Run compliance scan on all devices | Yes |
| GET | `/api/bulk/operations/:operationId/status` | Get bulk operation status | Yes |

### Policy Agent (WebSocket-backed push)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/agent/policy/apply` | Push policy to a connected agent | Yes |
| POST | `/api/agent/policy/apply-bulk` | Push policy to multiple agents | Yes |
| POST | `/api/agent/policy/remove` | Remove policy from agent | Yes |
| POST | `/api/agent/policy/check-compliance` | Check compliance via agent | Yes |
| POST | `/api/agent/policy/check-device-compliance` | Device-level compliance check | Yes |
| POST | `/api/agent/policy/detect-drift` | Detect configuration drift | Yes |
| POST | `/api/agent/policy/rollback` | Roll back policy on agent | Yes |
| POST | `/api/agent/policy/resync` | Resync all policies to agent | Yes |
| GET | `/api/agent/policy/status/:deviceId` | Get live policy status from agent | Yes |

### Backup & Disaster Recovery

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/backup/trigger` | Trigger backup (`body: { type: "incremental"\|"full" }`) | Yes |
| GET | `/api/backup/status` | Current backup status | Yes |
| GET | `/api/backup/history` | Backup history (`?limit=20`) | Yes |
| POST | `/api/backup/restore` | Restore from backup (`body: { backupId }`) | Yes |
| GET | `/api/dr/health` | DR health status | Yes |
| POST | `/api/dr/failover/test` | Test DR failover | Yes |
| GET | `/api/dr/replication/status` | Replication lag and status | Yes |
| POST | `/api/dr/failover/execute` | Execute DR failover (`body: { confirm: true }`) | Yes |

### Usage Examples

**Initiate enrollment:**

```bash
curl -X POST http://localhost:3003/api/enrollment/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "macos",
    "deviceName": "MacBook-Alice",
    "serialNumber": "C02XL0HJJGH6",
    "assignedUser": "alice@example.com"
  }'
```

**Execute remote command:**

```bash
curl -X POST http://localhost:3003/api/remote/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "dev-uuid",
    "action": "lock",
    "parameters": {}
  }'
```

**Trigger compliance scan:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3003/api/compliance/scan/dev-uuid
```

## WebSocket Protocol

Connect to `ws://device-service:3003/ws/devices` with headers:

- `X-Device-ID`: device UUID
- `X-Device-Platform`: `macos` / `windows` / `linux` / `ios` / `android`
- `X-Agent-Version`: agent build version

On connect, the server sends:

```json
{
  "type": "connection",
  "status": "connected",
  "connectionId": "...",
  "serverVersion": "1.0.0",
  "heartbeatInterval": 30000,
  "timestamp": "..."
}
```

The server pings every 30 seconds; clients must respond with `pong`. Connections that miss a heartbeat are terminated and removed from the connected agent registry.

## Events Published

| Routing Key | Trigger |
|---|---|
| `device.enrolled` | Device enrollment completed |
| `device.unenrolled` | Device removed from management |
| `device.compliance.scan.completed` | Compliance scan finished |
| `device.compliance.violated` | Compliance violation detected |
| `device.compliance.remediated` | Violation automatically remediated |
| `device.remote.action.executed` | Remote action sent |
| `device.wipe.initiated` | Remote wipe triggered |

## Events Subscribed

| Routing Key | Action |
|---|---|
| `policy.assigned` | Apply new policy to device |
| `policy.updated` | Refresh policy on affected devices |
| `identity.user.offboarded` | Unassign devices from offboarded user |

## Health Check

`GET /health` reports database, cache, and event bus connectivity, plus live metrics:

```json
{
  "status": "healthy",
  "service": "device-management-service",
  "version": "1.0.0",
  "uptime": 7200,
  "timestamp": "...",
  "checks": {
    "database": { "status": "healthy" },
    "cache": { "status": "healthy" },
    "eventBus": { "status": "healthy" }
  },
  "metrics": {
    "activeDevices": 142,
    "pendingEnrollments": 3,
    "complianceViolations": 7,
    "wsConnections": 98
  }
}
```

Returns `503` if any check is unhealthy.
