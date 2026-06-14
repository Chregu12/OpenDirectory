# Privileged Identity Management (PIM)

PIM is OpenDirectory's just-in-time (JIT) privileged access system. It enforces the principle of **never permanent admin rights** — users hold no standing elevated privileges. Instead, they request elevation for a specific role, the request is evaluated for risk, approved by authorised personnel, and the elevation expires automatically.

PIM is implemented in the `conditional-access` service (port **3007**) under `/api/v1/pim/`.

---

## 1. What is PIM

Traditional privileged access gives administrators permanent membership in groups like `Domain Admins`. This creates persistent attack surface: a compromised account immediately grants full domain control. PIM eliminates this by:

- Making all privileged roles **eligible** rather than **active** by default.
- Requiring a **justification** and **approval** before elevation is granted.
- Limiting elevation to a **configurable maximum duration** (4 hours for high-privilege roles).
- **Adding the user to the AD group** for the duration of the elevation, then removing them automatically.
- **Recording every action** taken during the elevated session.
- Continuously **monitoring risk score** and terminating sessions that exceed the threshold.

---

## 2. Role Definitions

### Built-in roles

| Role ID | Name | Policy | Max Duration | AD Group Integration |
|---------|------|--------|-------------|---------------------|
| `domain-admin` | Domain Administrator | high-privilege | 4 hours | `CN=Domain Admins,...` |
| `server-admin` | Server Administrator | medium-privilege | 8 hours | configurable |
| `security-admin` | Security Administrator | high-privilege | 4 hours | configurable |
| `database-admin` | Database Administrator | medium-privilege | 8 hours | configurable |

### Custom roles

Create a custom role with eligibility criteria:

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/roles \
  -H "Content-Type: application/json" \
  -d '{
    "id": "network-admin",
    "name": "Network Administrator",
    "description": "Access to network devices and firewall configuration",
    "policyId": "medium-privilege-policy",
    "adGroupDn": "CN=Network-Admins,OU=Groups,DC=corp,DC=example,DC=com",
    "permissions": ["firewall.configure", "router.admin", "switch.admin"],
    "eligibilityCriteria": {
      "requiredRoles": ["NET_ENGINEER", "IT_SUPPORT"],
      "minimumClearanceLevel": "CONFIDENTIAL",
      "trainingRequired": ["network_admin_training"]
    }
  }'
```

### Eligibility criteria

| Field | Description |
|-------|-------------|
| `requiredRoles` | User must hold at least one of these organisational roles |
| `minimumClearanceLevel` | One of: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `SECRET`, `TOP_SECRET` |
| `trainingRequired` | List of training course IDs that must be completed |

### Access policies

| Policy ID | Max Duration | Monitoring | Auto-approve threshold | Denial threshold |
|-----------|-------------|------------|----------------------|-----------------|
| `high-privilege-policy` | 4 hours | Yes | 0.20 | 0.90 |
| `medium-privilege-policy` | 8 hours | Yes | 0.30 | 0.95 |
| `low-privilege-policy` | 12 hours | No | 0.50 | 0.99 |

---

## 3. Requesting Elevation

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/requests \
  -H "Content-Type: application/json" \
  -d '{
    "requesterId": "alice",
    "roleId": "server-admin",
    "justification": "Emergency patch deployment on srv-web-01 following CVE-2026-1234",
    "duration": 4
  }'
# Returns: requestId, status, requiresApproval, estimatedApprovalTime, expiresAt
```

**What happens on request:**

1. Eligibility is checked (organisational role, clearance level, completed training).
2. Risk score is calculated (see section 5).
3. If `requiresApproval: false` and risk score < 0.30, the request is auto-approved immediately.
4. Otherwise, the request enters the approval queue and approvers are notified.
5. The request expires if not approved within 24 hours (escalation triggered at 4 hours).

---

## 4. Approval Workflow

### Multi-level approval chains

Each role defines an approval chain with levels and required approver counts:

```
domain-admin chain:
  Level 1: 1 approver required  (SECURITY_ADMIN, IT_DIRECTOR, or CISO)
  Level 2: 2 approvers required (SECURITY_ADMIN, IT_DIRECTOR, or CISO)
```

Approval at one level advances to the next. All levels must be satisfied before elevation is granted. An approver cannot approve their own request.

### Approve a request

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/requests/<requestId>/approve \
  -H "Content-Type: application/json" \
  -d '{
    "approverId": "security-officer",
    "approvalReason": "Verified ticket INC-4521. Approved for emergency patch window."
  }'
```

### Deny a request

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/requests/<requestId>/deny \
  -H "Content-Type: application/json" \
  -d '{
    "deniedBy": "security-officer",
    "denialReason": "No active incident ticket found. Request denied."
  }'
```

### List pending requests

```bash
curl http://conditional-access:3007/api/v1/pim/requests?status=PENDING
```

### Time limits

- Requests expire automatically after **24 hours** without action.
- After **4 hours** without action, the request is escalated (approvers are re-notified and the escalation is logged).

---

## 5. Risk Scoring

The risk score is a float between 0.0 (no risk) and 1.0 (maximum risk). It is calculated at request time and monitored continuously during active elevations.

### Request-time risk calculation

| Factor | Score added |
|--------|------------|
| Role: `domain-admin` | +0.50 |
| Role: `security-admin` | +0.40 |
| Role: `server-admin` | +0.30 |
| Role: other | +0.20 |
| Outside business hours (before 08:00 or after 18:00) | +0.10 |
| Weekend request | +0.10 |
| More than 3 elevation requests in the last 24 hours | +0.15 |
| More than 5 elevation requests in the last 24 hours | +0.15 (additional) |
| Any active elevation already in progress | +0.10 per active elevation |

Score is capped at 1.0.

**Thresholds (medium-privilege-policy):**
- Score < 0.30: auto-approve
- Score >= 0.30 and < 0.80: normal approval required
- Score >= 0.80: additional approval required
- Score >= 0.95: auto-deny

### Activity-time risk scoring

Each activity recorded during an elevation has its own risk score:

| Activity type | Base risk |
|--------------|-----------|
| `SCHEMA_MODIFY` | 0.80 |
| `USER_DELETE` | 0.70 |
| `GROUP_MODIFY` | 0.50 |
| `SERVICE_STOP` | 0.40 |
| Other | 0.20 |
| Failed activity | +0.20 |

---

## 6. Active Elevations

When an elevation is approved:

1. The user is **added to the AD group** (`adGroupDn`) specified on the role — this immediately grants the actual permissions in Active Directory.
2. A session is created with a `sessionToken` and expiry time.
3. Session monitoring begins (if enabled by the policy).
4. The session timer is visible in the UI under **PIM → Active Elevations**.

### List active elevations

```bash
curl http://conditional-access:3007/api/v1/pim/elevations?status=ACTIVE
```

### Revoke an elevation early

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/elevations/<elevationId>/revoke \
  -H "Content-Type: application/json" \
  -d '{"revokedBy": "security-officer", "reason": "Suspicious activity detected"}'
```

**On expiry or revocation:** the user is immediately removed from the AD group and the `security.elevation.revoked` event is published to the event bus.

### Auto-termination

If the continuous risk score exceeds **0.95** during an active session (e.g. due to a high-risk activity), the elevation is auto-terminated and a critical alert is raised.

---

## 7. Session Recording

Every action taken during a privileged elevation is recorded. Session data is stored by the `SessionRecorder` and accessible via the PIM Sessions API.

```bash
# List all sessions (filterable by userId, roleId, date range)
curl "http://conditional-access:3007/api/v1/pim/sessions?userId=alice&from=2026-06-01"

# Get a specific session record
curl http://conditional-access:3007/api/v1/pim/sessions/<sessionRecordId>
```

Each session record contains:
- `elevationId`, `userId`, `roleId`
- `startedAt`, `endedAt`
- `activities[]` — every action with `type`, `details`, `riskScore`, `timestamp`, `success`

---

## 8. Session Replay

The Session Replay view renders a chronological timeline of all activities within an elevation window.

```bash
curl http://conditional-access:3007/api/v1/pim/sessions/<sessionRecordId>/replay
# Returns: sessionRecordId, activities[], total
```

### Colour coding in the UI

| Risk score range | Colour |
|-----------------|--------|
| < 0.40 | Green (low risk) |
| 0.40 – 0.70 | Yellow (medium risk) |
| > 0.70 | Red (high risk) |

Activities are displayed on a timeline with the actor, timestamp, risk level, and expandable detail panel.

---

## 9. Break-Glass Emergency Access

Break-glass is for genuine emergencies where the normal approval workflow cannot be completed in time (e.g. primary approvers are unreachable during a critical incident).

### Request break-glass access

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/breakglass/request \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "alice",
    "reason": "Primary DC unresponsive. SLA breach imminent. All approvers unreachable.",
    "systemsAffected": ["dc01.corp.example.com", "samba-ad-dc"],
    "estimatedDuration": 2
  }'
# Returns: breakGlassId, status: PENDING_ACTIVATION
```

### Activate (requires a second manager — dual control)

A **second authorised manager** (not the requester) must activate the break-glass request:

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/breakglass/<breakGlassId>/activate \
  -H "Content-Type: application/json" \
  -d '{"managerId": "it-director"}'
# Returns: breakGlassId, status: ACTIVE, expiresAt
```

Dual control is enforced: the activating manager cannot be the same person as the requester.

### Maximum duration

Break-glass sessions are limited to **4 hours**. They cannot be extended; a new request must be submitted after expiry.

### Every action during break-glass is recorded

Every activity during the break-glass window is logged with severity `critical`. Alerts are sent immediately to `audit-service` and `notification-service`.

### Terminate break-glass

```bash
curl -X POST http://conditional-access:3007/api/v1/pim/breakglass/<breakGlassId>/terminate \
  -H "Content-Type: application/json" \
  -d '{"terminatedBy": "alice", "outcome": "Resolved: DC restarted successfully"}'
```

### Audit break-glass events

```bash
curl "http://conditional-access:3007/api/v1/pim/breakglass?from=2026-06-01"
```

---

## 10. AD Integration

PIM has a built-in Active Directory bridge that synchronises elevation state with AD group membership in real time.

### On elevation approval

The user is added to the AD group configured in `adGroupDn` on the role:

```
POST http://enterprise-directory/api/groups/<encodedGroupDn>/members
Body: {"userId": "<userId>"}
```

This call is non-blocking with a 5-second timeout. If the AD sync fails, the elevation is still granted locally and a warning is logged (PIM never blocks elevation for AD failures).

### On expiry or revocation

The user is removed from the AD group:

```
DELETE http://enterprise-directory/api/groups/<encodedGroupDn>/members
Body: {"userId": "<userId>"}
```

### Event bus integration

PIM publishes the following events to the event bus (routing key namespace: `security.elevation.*`):

| Event | Routing Key | Trigger |
|-------|------------|---------|
| Elevation requested | `security.elevation.requested` | User submits a request |
| Elevation approved | `security.elevation.approved` | All chain levels satisfied |
| Elevation denied | `security.elevation.denied` | Approver denies |
| Elevation expired | `security.elevation.expired` | Request not approved in time |
| Elevation revoked | `security.elevation.revoked` | Manual or auto-termination |
| Break-glass activated | `security.breakglass.activated` | Manager activates break-glass |
| Break-glass terminated | `security.breakglass.terminated` | Session ends |
