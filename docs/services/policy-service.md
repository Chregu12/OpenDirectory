# policy-service

**Port:** 3004  
**Database:** PostgreSQL (policies)  
**Language:** Node.js 18+

## Overview

The policy service manages the complete lifecycle of security, software, and configuration policies across all platforms. It stores policy definitions in PostgreSQL, compiles them into platform-native formats (Windows Registry/ADMX, macOS profiles, Linux shell scripts), and calculates Resultant Set of Policy (RSoP) to determine the merged effective policy for any device or user context.

The service ships three platform compilers (Windows, macOS, Linux), an inheritance engine that follows AD-style precedence (Local → Site → Domain → OU), and a conflict resolver that applies priority rules when settings clash. Policies can be linked to OUs, groups, sites, or domains. WMI filters (Windows) and security filters allow fine-grained targeting. All mutations are recorded in `policy_audit_log` and published to the event bus.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3004` | HTTP listen port |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_NAME` | `policies` | PostgreSQL database |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | — | PostgreSQL password |
| `LOG_LEVEL` | `info` | Winston log level |
| `EVENT_BUS_URL` | — | gRPC event bus endpoint |

## API Endpoints

### Policies CRUD

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies` | List policies (supports `?type=`, `?status=`, `?platform=`, `?page=`, `?limit=`) | Yes |
| POST | `/api/policies` | Create policy | Yes |
| GET | `/api/policies/:id` | Get policy | Yes |
| PUT | `/api/policies/:id` | Update policy (partial updates supported) | Yes |
| DELETE | `/api/policies/:id` | Delete policy (returns 204) | Yes |

**Valid policy types:** `security`, `software`, `registry`, `network`, `firewall`, `encryption`, `password`, `compliance`

**Create policy body:**

```json
{
  "name": "Enforce BitLocker",
  "description": "Require BitLocker on all Windows workstations",
  "type": "encryption",
  "platform": "windows",
  "rules": [],
  "settings": {
    "bitlocker": {
      "enabled": true,
      "recoveryKey": "escrow"
    }
  },
  "priority": 50,
  "enforce": true,
  "block_inheritance": false,
  "wmi_filter": null,
  "security_filter": null,
  "created_by": "admin"
}
```

### Activation

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/policies/:id/activate` | Set policy status to `active` | Yes |
| POST | `/api/policies/:id/deactivate` | Set policy status to `inactive` | Yes |

### Assignments

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies/:id/assignments` | List targets this policy is assigned to | Yes |
| POST | `/api/policies/:id/assign` | Assign policy to a target | Yes |

**Assign body:**
```json
{
  "targetType": "device",
  "targetId": "dev-uuid",
  "assigned_by": "admin"
}
```

`targetType` accepts: `device`, `user`, `group`, `ou`, `site`, `domain`.

### Evaluation & RSoP

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/policies/evaluate` | Evaluate active policies for a context | Yes |
| POST | `/api/policies/rsop` | Compute Resultant Set of Policy | Yes |

**RSoP body:**
```json
{
  "deviceId": "dev-uuid",
  "userId": "user-uuid",
  "context": {}
}
```

Returns the merged effective settings and source attribution for each setting.

```bash
curl -X POST http://localhost:3004/api/policies/rsop \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"deviceId":"dev-uuid","userId":"user-uuid"}'
```

### Templates

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies/templates` | List available policy templates | Yes |
| POST | `/api/policies/from-template` | Create policy from template | Yes |

**From-template body:**
```json
{
  "templateId": "windows-security-baseline",
  "name": "My Security Baseline",
  "priority": 50,
  "created_by": "admin"
}
```

### Platform Compilation

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/policies/:id/compile/:platform` | Compile policy for a target platform | Yes |

`:platform` must be `windows`, `macos`, or `linux`.

```bash
curl -X POST http://localhost:3004/api/policies/pol-uuid/compile/windows \
  -H "Authorization: Bearer $TOKEN"
```

Response includes `compiled` with the platform-native artifact (Registry export, `.mobileconfig` XML, or shell script).

### Inheritance Chain

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies/inheritance/:ouId` | Inheritance chain for an OU | Yes |
| GET | `/api/policies/inheritance/:targetType/:targetId` | Inheritance chain for any target type | Yes |

`:targetType` accepts: `ou`, `site`, `domain`, `device`, `group`.

### Policy Links

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/policies/:id/link` | Link policy to a target | Yes |
| DELETE | `/api/policies/:id/link/:linkId` | Remove a link | Yes |
| GET | `/api/policies/:id/links` | List links for a policy | Yes |

**Link body:**
```json
{
  "target_type": "ou",
  "target_id": "ou-uuid",
  "target_name": "OU=Engineering,DC=example,DC=com",
  "enforce": false,
  "link_order": 1
}
```

### Conflict Detection

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies/conflicts` | Detect conflicts among active policies | Yes |

Returns a list of setting keys that are defined by multiple active policies, along with the resolution (highest-priority policy wins).

### WMI Filters (Windows)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/policies/:id/wmi-filter` | Attach WMI filter to a policy | Yes |

### Blueprints

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/policies/blueprints` | List policy blueprints | Yes |
| POST | `/api/policies/blueprints` | Create blueprint | Yes |
| GET | `/api/policies/blueprints/:id` | Get blueprint | Yes |
| PUT | `/api/policies/blueprints/:id` | Update blueprint | Yes |
| DELETE | `/api/policies/blueprints/:id` | Delete blueprint | Yes |
| POST | `/api/policies/blueprints/:id/apply` | Apply blueprint to a target | Yes |

### Health

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/health` | Service health check | No |

## Events Published

| Routing Key | Trigger |
|---|---|
| `policy.created` | New policy created |
| `policy.updated` | Policy modified |
| `policy.deleted` | Policy deleted |
| `policy.activated` | Policy status set to active |
| `policy.deactivated` | Policy status set to inactive |
| `policy.assigned` | Policy assigned to a target |
| `policy.violated` | Violation detected during evaluation (when `enforce=true` and context reports violation) |

## Events Subscribed

| Routing Key | Action |
|---|---|
| `device.enrolled` | Evaluate applicable policies for new device |
| `identity.user.created` | Evaluate applicable policies for new user |

## Health Check

`GET /health` checks the PostgreSQL connection:

```json
{
  "status": "healthy",
  "service": "policy-service",
  "database": "connected",
  "timestamp": "2026-06-07T12:00:00.000Z"
}
```

Returns `503` if the database connection fails.
