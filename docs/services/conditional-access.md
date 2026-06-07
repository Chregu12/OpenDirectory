# conditional-access

**Port:** 3007  
**Database:** PostgreSQL (PIM sessions, audit)  
**Language:** Node.js 18+

## Overview

The conditional access service implements zero-trust access control, privileged identity management (PIM), and device compliance scoring. It evaluates every access request against a configurable set of policies (user risk, device health, location, network, application sensitivity) and issues an ALLOW, MFA_REQUIRED, or DENY decision. Access decisions are published to the event bus so other services can react in near real time.

PIM sessions support multi-approver workflows: a user requests a role elevation, one or more managers approve it, and the elevated session runs for a bounded duration with full activity recording. The session recorder captures user actions during elevated sessions so they can be replayed for forensic audit. Break-glass accounts allow emergency access that bypasses normal approval chains — every break-glass activation is immediately published as a critical security event.

The service also handles Windows Autopilot deployment orchestration, disk encryption management (BitLocker/FileVault/LUKS), and EDR integration for threat intelligence feeds.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3007` | HTTP listen port |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS origins |
| `DB_HOST` | `localhost` | PostgreSQL host (PIM session store) |
| `DB_NAME` | `conditional_access` | PostgreSQL database |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | — | PostgreSQL password |
| `JWT_SECRET` | — | JWT validation key (shared with auth-service) |
| `EVENT_BUS_URL` | — | gRPC event bus endpoint |

## API Endpoints

All endpoints are under the prefix `/api/v1`. The prefix-level `authMiddleware` validates JWT tokens for all routes.

### Conditional Access Policies

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/conditional-access/policies` | List CA policies | Yes |
| POST | `/api/v1/conditional-access/policies` | Create CA policy | Yes |
| GET | `/api/v1/conditional-access/policies/:id` | Get policy | Yes |
| PUT | `/api/v1/conditional-access/policies/:id` | Update policy | Yes |
| DELETE | `/api/v1/conditional-access/policies/:id` | Delete policy | Yes |
| POST | `/api/v1/conditional-access/evaluate` | Evaluate access for a request context | Yes |

**Evaluate body:**
```json
{
  "userId": "user-uuid",
  "deviceId": "dev-uuid",
  "application": "gitlab",
  "resource": "/admin",
  "ipAddress": "192.168.1.10",
  "userAgent": "Mozilla/5.0 ..."
}
```

**Response:**
```json
{
  "decision": "ALLOW",
  "reasons": [],
  "riskScore": 0.12,
  "sessionDuration": 28800
}
```

`decision` values: `ALLOW`, `MFA_REQUIRED`, `DENY`, `BLOCK`.

```bash
curl -X POST http://localhost:3007/api/v1/conditional-access/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-uuid","deviceId":"dev-uuid","application":"gitlab"}'
```

### Device Compliance Scoring

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/device-compliance/devices` | List device compliance states | Yes |
| GET | `/api/v1/device-compliance/devices/:deviceId` | Get compliance score for a device | Yes |
| POST | `/api/v1/device-compliance/devices/:deviceId/evaluate` | Force compliance re-evaluation | Yes |
| GET | `/api/v1/device-compliance/policies` | List compliance policies | Yes |
| POST | `/api/v1/device-compliance/policies` | Create compliance policy | Yes |

### Encryption Management

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/encryption/status` | List encryption status for all devices | Yes |
| GET | `/api/v1/encryption/status/:deviceId` | Get encryption status for device | Yes |
| POST | `/api/v1/encryption/enable` | Enable encryption on a device | Yes |
| POST | `/api/v1/encryption/disable` | Disable encryption | Yes |
| POST | `/api/v1/encryption/rotate-key` | Rotate encryption key | Yes |
| GET | `/api/v1/encryption/recovery-keys` | List escrowed recovery keys | Admin |

### Deployment (Autopilot / Zero-Touch)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/deployment/profiles` | List Autopilot deployment profiles | Yes |
| POST | `/api/v1/deployment/profiles` | Create deployment profile | Yes |
| POST | `/api/v1/deployment/enroll` | Enroll a device via Autopilot | Yes |
| GET | `/api/v1/deployment/status/:deviceId` | Get deployment status | Yes |

### PIM — Role Elevations

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/pim/roles` | List available privileged roles | Yes |
| POST | `/api/v1/pim/roles` | Create privileged role | Admin |
| POST | `/api/v1/pim/elevations/request` | Request a role elevation | Yes |
| GET | `/api/v1/pim/elevations` | List pending and active elevations | Yes |
| POST | `/api/v1/pim/elevations/:id/approve` | Approve elevation request | Admin |
| POST | `/api/v1/pim/elevations/:id/deny` | Deny elevation request | Admin |
| POST | `/api/v1/pim/elevations/:id/revoke` | Revoke an active elevation | Admin |

### PIM — Session Recording

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/pim/sessions` | List session records (params: userId, roleId, from, to, limit) | Admin |
| GET | `/api/v1/pim/sessions/:id` | Get session record details | Admin |
| GET | `/api/v1/pim/sessions/:id/replay` | Replay session activity log | Admin |

### PIM — Break-Glass

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/v1/pim/breakglass/request` | Submit break-glass request | Yes |
| POST | `/api/v1/pim/breakglass/:id/activate` | Manager activates break-glass | Admin |
| POST | `/api/v1/pim/breakglass/:id/terminate` | Terminate active break-glass session | Admin |
| GET | `/api/v1/pim/breakglass` | List break-glass events (params: from, to) | Admin |

**Break-glass request body:**
```json
{
  "userId": "user-uuid",
  "reason": "Production database unreachable, on-call SRE requires root access",
  "systemsAffected": ["prod-db-01", "prod-db-02"],
  "estimatedDuration": 3600
}
```

```bash
# Request break-glass
curl -X POST http://localhost:3007/api/v1/pim/breakglass/request \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-uuid","reason":"Incident response","estimatedDuration":1800}'
```

### Emergency Access

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/emergency-access/accounts` | List emergency access accounts | Admin |
| POST | `/api/v1/emergency-access/accounts` | Create emergency access account | Admin |
| POST | `/api/v1/emergency-access/activate` | Activate emergency access | Admin |
| GET | `/api/v1/emergency-access/audit` | Audit log for emergency access usage | Admin |

### System

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/health` | Service health check | No |
| GET | `/discovery` | Service capability and endpoint listing | No |

## Events Published

| Routing Key | Trigger |
|---|---|
| `security.access.granted` | Access evaluated and allowed |
| `security.access.denied` | Access evaluated and denied or blocked |
| `security.pim.granted` | Role elevation approved |
| `security.pim.revoked` | Role elevation revoked |
| `security.emergency.access.activated` | Break-glass or emergency access activated |

## Events Subscribed

| Routing Key | Action |
|---|---|
| `device.compliance.violated` | Downgrade device compliance score |
| `device.enrolled` | Evaluate initial compliance state |
| `identity.user.created` | Bootstrap access policies for new user |

## Health Check

`GET /health`:

```json
{
  "status": "healthy",
  "timestamp": "2026-06-07T12:00:00.000Z",
  "service": "conditional-access",
  "version": "1.0.0"
}
```
